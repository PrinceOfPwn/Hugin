## Synthesis Summary

This batch of 40 units from SANS SEC670 consists almost entirely of slide titles, table-of-contents pages, and multiple-choice review questions with no technical body — the actual lab content lives in referenced eWorkbooks that are not included. The material maps conceptually to T-007/T-013 (injection labs: Call_DirectInjection, APCInjection, ThreadHijacker, ClassicDLLInjection, The Loader), T-016 (AMSI No More and UnhookTheHook labs), T-017 (InitToWinit AppInit_DLLs, OhMyWMI WMI persistence, NotInService service hiding), T-021 (UACBypass-Research), T-022 (No Caller ID HTTP C2), and T-023 (OS Info, FileFinder, CustomShell, ShadowCraft host survey and shell labs). The training material does not itself fill a knowledge gap that source code reading cannot — it surfaces lab titles and review questions without procedural detail. The genuinely extractable graph value is in the OS-internals concepts the slide questions name (AppInit_DLLs registry persistence, AddMonitor port monitor API, SilentProcessExit registry key, PE-sieve as a defensive scanner, MS-DOS header byte layout, ITaskScheduler COM enumeration, and the CREATE_SUSPENDED pre-LdrInitializeThunk hook window).

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "pe-sieve-defensive-scanner"
    target: T-013
    type: detects
    rationale: "Unit 29 (Lab 1.1: PE-sieve) describes PE-sieve as a defensive scanner that catches injection methods; T-013 (Remaining Methods) covers the bulk of injection techniques (hollowing, mapping, stomping, overloading, callback, fiber, Early Bird, PE loader) that PE-sieve is designed to detect."
  - source: "pe-sieve-defensive-scanner"
    target: T-007
    type: detects
    rationale: "Unit 29 references PE-sieve detecting injection methods broadly; T-007 (Pool Party and the principal injection family) is the main injection card in the vault and a primary PE-sieve scan target."
  - source: "appinit-dlls-registry"
    target: T-017
    type: alternative_to
    rationale: "Unit 1 (InitToWinit bootcamp challenge) frames AppInit_DLLs as a DLL execution foothold. T-017 documents COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist as its five persistence layers; AppInit_DLLs is an alternative persistence vector not covered by T-017."
  - source: "amsi-no-more-lab"
    target: T-016
    type: enhances
    rationale: "Unit 18 (AMSI No More bootcamp challenge) and T-016 (EDR Evasion Suite) both include AMSI bypass as a capability. The lab exercises the AMSI-bypass technique documented in T-016."
  - source: "unhook-the-hook-lab"
    target: T-016
    type: enhances
    rationale: "Unit 38 (UnhookTheHook lab tested against Bitdefender and other EDRs) exercises the NTDLL unhook capability documented in T-016, validating the technique against real EDR products."
  - source: "silentprocessexit-registry-monitoring"
    target: T-017
    type: concept_link
    rationale: "Unit 36 references SilentProcessExit as a registry key usable for process-termination monitoring. The same key is abuseable as a persistence trigger and relates to T-017's persistence space without being one of its five layers."
  - source: "process-creation-hook-states"
    target: T-012
    type: enables
    rationale: "Unit 22 frames a review question about which process-creation state has no hooks implemented. The CREATE_SUSPENDED pre-LdrInitializeThunk window is precisely what T-012 Early Cascade exploits to queue an APC before EDR userland hooks are installed."
# Most units in this batch are slide titles and TOC pages without technical body; few relationships are supportable from the material alone.
```

### Concept Nodes

```yaml
concepts:
  - id: "appinit-dlls-registry"
    name: "AppInit_DLLs Registry Key"
    category: os-internal
    description: "The HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs registry value causes specified DLLs to be loaded into any process that loads user32.dll. Unit 1 (InitToWinit bootcamp challenge) frames AppInit_DLLs as a DLL execution foothold. Modern Windows restricts loading based on the RequireSignedAppInit_DLLs flag and architecture matching, but the mechanism remains a documented persistence and injection vector distinct from the techniques in T-017."
    relevant_to: []
    tags: [persistence, dll-execution, registry, orphan, appinit]

  - id: "addmonitor-port-monitor-api"
    name: "AddMonitor Port Monitor API"
    category: os-internal
    description: "The AddMonitor API (winspool.drv) installs a port monitor under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors. Unit 35 explicitly distinguishes AddMonitor from plausible-but-wrong candidate names (CreateNewMonitor, AddNewMonitor) as the correct API for installing a new port monitor. Port monitor DLLs load into the spoolsv.exe service context at service startup and survive reboot, making this a recognized persistence vector not present in the vault's T-017."
    relevant_to: []
    tags: [persistence, port-monitor, spooler, registry, orphan, api-resolution]

  - id: "silentprocessexit-registry-monitoring"
    name: "SilentProcessExit Registry Key"
    category: os-internal
    description: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit can be configured to trigger actions when a process exits, including attaching a debugger or launching a monitoring process. Unit 36 lists SilentProcessExit and Debugger as registry keys usable to watch for process termination. Defenders use the key for forensic monitoring; attackers abuse the same key as a persistence trigger that fires when a sacrificial process exits."
    relevant_to: []
    tags: [persistence, registry, process-termination, image-load, orphan]

  - id: "pe-sieve-defensive-scanner"
    name: "PE-sieve Memory Scanner"
    category: defense-mechanism
    description: "PE-sieve is a defensive scanning tool that inspects running processes for malware artifacts and injection indicators. Unit 29 (Lab 1.1) positions PE-sieve as a 'hackerverse' GitHub project that catches injection methods. The scanner is used during payload development to verify which injection techniques leave detectable artifacts in process memory (unbacked executable regions, modified .text sections, replaced PE images)."
    relevant_to: [T-007, T-013, T-016]
    tags: [memory-scan, detection, scanner, defensive-tool, pe-sieve]

  - id: "ms-dos-header-byte-layout"
    name: "MS-DOS Header Byte Layout"
    category: windows-structure
    description: "Unit 30 frames the byte following the MS-DOS header as 0x00 (the correct answer among 0x00, 0x90, 0x5A). This byte is the start of the MS-DOS stub program that follows the IMAGE_DOS_HEADER in a PE file. The stub is a minimal DOS program that typically prints 'This program cannot be run in DOS mode' and exits; its first byte is part of the stub's instruction sequence. The unit reinforces that PE parsing begins with recognizing the DOS header and stub before the e_lfanew pointer transitions to the NT headers."
    relevant_to: []
    tags: [pe-format, ms-dos-header, pe-parsing, orphan]

  - id: "itaskscheduler-com-interface"
    name: "ITaskScheduler COM Enumeration Interface"
    category: os-internal
    description: "Unit 11 frames ITaskScheduler as the COM interface used to create enumeration objects for scheduled tasks (vs. IUnknown or 'IBelieve'). ITaskScheduler is the legacy COM interface exposed by the Windows Task Scheduler service; modern code uses ITaskService, but ITaskScheduler remains the documented interface for task enumeration on legacy Windows and is referenced in T-017's schtask persistence work."
    relevant_to: [T-017]
    tags: [com, scheduled-tasks, enumeration, itaskscheduler]

  - id: "process-creation-hook-states"
    name: "Process Creation Pre-LdrInitializeThunk Window"
    category: os-internal
    description: "Unit 22 frames a review question about process-creation states (Suspended, Terminated, Running) and the stage at which hooks are not yet implemented. In a CREATE_SUSPENDED process, the loader (LdrInitializeThunk) has not yet executed, so userland EDR hook DLLs have not been injected into the new process. This pre-LdrInitializeThunk window is the basis for T-012 Early Cascade APC injection and informs T-014 NtCreateUserProcess and T-015 PPID Spoofing tradecraft."
    relevant_to: [T-012, T-014, T-015]
    tags: [process-creation, edr-hooks, create-suspended, loader-init, ldrinitializethunk]

  - id: "sal-source-annotation-language"
    name: "SAL Source Annotation Language"
    category: os-internal
    description: "Unit 8 frames SAL as standing for 'Source-code annotation language' (vs. 'Structured annotation language' or 'Silent analysis language'). Unit 24 (Lab 1.5: Safer with SAL) notes that SAL annotations make code more understandable. SAL is Microsoft's annotation syntax for expressing buffer sizes, pointer validity, and call contracts on Windows API functions, used in headers like winnt.h to communicate contract expectations between callers and callees."
    relevant_to: []
    tags: [sal, annotations, windows-api, code-contracts, orphan]
```

### Detection Insights

```yaml
detection:
  - indicator: "PE-sieve scan flagging unbacked executable memory or modified module .text sections"
    source: memory-scan
    confidence: medium
    relevant_to: [T-007, T-013, T-016]
    description: "Unit 29 (Lab 1.1: PE-sieve) describes PE-sieve as a defensive scanner that catches injection methods. PE-sieve scans running processes for injection artifacts — unbacked executable memory regions (VadS nodes with no file backing), modified module .text sections (indicating hooks or stomping), and replaced PE images. Operators can run PE-sieve during payload development to verify which injection techniques leave detectable memory artifacts."
    bypassed_by: "not discussed"
  - indicator: "SilentProcessExit registry configuration triggering on sacrificial process exit"
    source: windows-security-log
    confidence: low
    relevant_to: []
    description: "Unit 36 references SilentProcessExit (and Debugger) as registry keys usable to watch for process termination. Defenders can configure SilentProcessExit to generate an event or launch a monitoring process when a tracked process exits, exposing persistence mechanisms that rely on process-termination triggers. The same key is dual-use as an attacker persistence vector."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "PE-sieve Detected Unbacked Executable Memory"
    logsource: memory-scan
    condition_summary: "PE-sieve scanner output flags an in-process region with PAGE_EXECUTE* permissions and no backing module on disk"
  - title: "SilentProcessExit Registry Configuration"
    logsource: windows-security
    condition_summary: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit configured with ReportingMode or MonitorProcess values on a non-default process"
# Batch does not surface ETW provider GUIDs, Sysmon event IDs, or specific kernel callbacks; the material is slide titles without detection-telemetry body.
```

### Operational Chains

```yaml
chains:
  - name: "SEC670 Book Progression Chain"
    description: "Operational sequence implied by SEC670 book ordering: recon → loader → injection → persistence → evasion → C2"
    steps:
      - technique: T-023
        role: "OS Info and FileFinder labs gather host survey and directory enumeration (Book 1/2)"
      - technique: T-013
        role: "The Loader lab executes shellcode locally and across process boundaries (Book 5)"
      - technique: T-007
        role: "Call_DirectInjection, APCInjection, ThreadHijacker labs inject into remote processes (Book 3)"
      - technique: T-017
        role: "NotInService (services), InitToWinit (AppInit_DLLs), OhMyWMI (WMI) labs establish persistence footholds (Book 4)"
      - technique: T-016
        role: "UnhookTheHook lab validates NTDLL unhooking against Bitdefender and other EDRs (Book 5)"
      - technique: T-022
        role: "No Caller ID lab implements HTTP C2 transport using HTTP libraries (Book 5)"
    notes: "The SEC670 book ordering (Book 1 Windows Tool Development, Book 3 Operational Actions, Book 4 Persistence, Book 5 Enhancing Implant) implies an operational sequence. Individual lab content is in the eWorkbook, which is not included in this batch; the chain is structural rather than procedurally detailed."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "appinit-dlls-persistence-coverage"
    title: "AppInit_DLLs Persistence Coverage Gap"
    kind: coverage-gap
    description: "Unit 1 (InitToWinit bootcamp challenge) and Units 6, 16, 33 list AppInit_DLLs as a persistence and DLL-execution foothold. The vault's T-017 Five-Layer Persistence card covers COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not include AppInit_DLLs. This is a documented Windows persistence mechanism with defender detection coverage (RequireSignedAppInit_DLLs, image-load ETW) and would merit either an addition to T-017 or a standalone persistence card."
    would_relate_to: [T-017]
    source_units: ["unit 1", "unit 6", "unit 16", "unit 33"]
    tags: [persistence, appinit, dll-execution, registry, coverage-gap]

  - id: "port-monitor-persistence"
    title: "AddMonitor Port Monitor Persistence"
    kind: proposed-technique
    description: "Unit 35 explicitly identifies AddMonitor (vs. CreateNewMonitor or AddNewMonitor) as the correct API to install a port monitor. Port monitor persistence survives reboot inside spoolsv.exe and is a recognized tradecraft distinct from T-017's persistence layers, which target userland and boot-time triggers rather than service-hosted monitor DLLs. The vault has no card covering spooler-based persistence and would benefit from one."
    would_relate_to: [T-017]
    source_units: ["unit 35"]
    tags: [persistence, port-monitor, spooler, addmonitor, proposed-technique]

  - id: "silentprocessexit-trigger-persistence"
    title: "SilentProcessExit Registry Trigger Persistence"
    kind: proposed-technique
    description: "Unit 36 references SilentProcessExit as a registry key that can watch for process termination. The same key is abuseable as a persistence mechanism by configuring ReportingMode and MonitorProcess values to relaunch an implant when a sacrificial process exits. The vault does not currently document this capability, and it sits at the intersection of T-017 (persistence) and process-lifecycle monitoring."
    would_relate_to: [T-017]
    source_units: ["unit 36"]
    tags: [persistence, silentprocessexit, registry, process-termination, proposed-technique]

  - id: "pe-sieve-defensive-validation"
    title: "PE-sieve as Defensive Validation Tool"
    kind: coverage-gap
    description: "Unit 29 dedicates Lab 1.1 to PE-sieve as a defensive scanner that catches injection methods. The vault documents 14+ injection techniques in T-007 and T-013 but does not document the defensive tooling an operator should run during development to validate which techniques leave memory artifacts. PE-sieve, Moneta, and HollowsHunter form a class of free defensive scanners operators use pre-engagement to verify evasion claims; this deserves a cross-cutting concept reference or dedicated validation-tradecraft note in the vault."
    would_relate_to: [T-007, T-013, T-016]
    source_units: ["unit 29"]
    tags: [pe-sieve, memory-scan, defensive-validation, coverage-gap]

  - id: "sec670-cross-source-convergence"
    title: "SEC670 Convergence on Injection and Evasion Tradecraft"
    kind: cross-source-convergence
    description: "Multiple SEC670 labs (Call_DirectInjection, APCInjection, ThreadHijacker, ClassicDLLInjection, The Loader, UnhookTheHook, AMSI No More) converge on the same injection and EDR evasion technique space the vault documents in T-007, T-013, and T-016. The convergence indicates strong tradecraft consensus across SEC670, MalDev Academy, and CRTO on injection primitives and AMSI/NTDLL-unhook evasion as core red team capabilities, reinforcing the vault's existing technique card selection."
    would_relate_to: [T-007, T-013, T-016]
    source_units: ["unit 1", "unit 3", "unit 18", "unit 20", "unit 31", "unit 32", "unit 37", "unit 38"]
    tags: [cross-source, convergence, injection, evasion, amsi, unhook]

  - id: "sec670-bootcamp-slide-titles-low-yield"
    title: "SEC670 Bootcamp Slide Titles Low Yield"
    kind: coverage-gap
    description: "The majority of units in this batch are bootcamp challenge titles (NotInService, InitToWinit, OhMyWMI, CustomShell, ShadowCraft, So You Think You Can Type, AMSI No More) without technical body. The actual lab content is in referenced eWorkbooks not included in the corpus extract. This indicates a coverage gap in the source material rather than the vault — the eWorkbook pages would be needed to surface technique-level details worth adding to graph concept nodes."
    would_relate_to: []
    source_units: ["unit 1", "unit 9", "unit 15", "unit 16", "unit 18", "unit 19", "unit 34", "unit 40"]
    tags: [coverage-gap, source-material-limitation, sec670, bootcamp]
```