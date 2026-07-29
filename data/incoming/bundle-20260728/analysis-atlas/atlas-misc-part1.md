## Synthesis Summary

This batch of SANS SEC670 material (Book 4 — "Persistence: Die Another Day" plus related review questions from Books 2 and the consolidated All-books-in-one file) maps primarily to T-017 (Five-Layer Persistence), with secondary mapping to T-013 (Remaining Injection Methods) for the classic CreateRemoteThread DLL injection walk-through, and to T-012 (Early Cascade) for the APC-queue thread-quantum review question. The material documents persistence surfaces the source code does not address at the operational level: AppInit_DLLs registry semantics (User32.dll linking requirement, LoadAppInit_DLLs gate, infinite-loop avoidance), IFEO with silent.exe variants, Silent Process Exit via Gflags/GlobalFlag configuration, service ImagePath/binPath/FailureCommand modification, port monitor persistence, and WMI event subscriptions. It also surfaces Windows-internals review material (WIN32_FIND_DATA, MS-DOS header bytes, thread-as-schedulable-entity, KUSER_SHARED_DATA, SDDL, ITaskScheduler COM interface) that the vault's technique cards assume as background knowledge. Several persistence methods described (AppInit_DLLs, IFEO, Silent Process Exit, port monitors, service modification) are not in T-017's documented five-layer set, representing coverage gaps flagged in LGTM Notes. No units were skipped as off-theme.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: concept-appinit-dlls
    target: T-017
    type: alternative_to
    rationale: "AppInit_DLLs forces DLL load into every User32-linked user process on creation, serving the same persistence purpose as T-017's five layers but through a different mechanism (registry-driven loader hook vs. COM/NTFS-EA/schtask/TLS)."

  - source: concept-silent-process-exit
    target: T-017
    type: alternative_to
    rationale: "Silent Process Exit persistence via GlobalFlag + ReportingMode + MonitorProcess registry keys triggers an attacker payload when a watched process exits, an alternative persistence trigger to T-017's documented layers."

  - source: concept-service-imagepath-modification
    target: T-017
    type: alternative_to
    rationale: "Modifying the ImagePath/binPath/FailureCommand of an existing or newly created service achieves the same reboot-survivable execution as T-017's persistence layers, but through SCM rather than COM/registry/schtask."

  - source: concept-classic-dll-injection
    target: T-013
    type: concept_link
    rationale: "The classic CreateRemoteThread DLL injection flow (obtain handle → allocate memory → write DLL path → spawn remote thread) is the legacy variant documented in T-013's Remaining Methods injection set."

  - source: concept-apc-queue-thread-quantum
    target: T-012
    type: enables
    rationale: "The material's review question establishes that APC queue processing occurs during a thread's quantum — the same scheduling mechanism Early Cascade (T-012) relies on for queuing pre-LdrInitializeThunk APCs."

  - source: concept-ifeo-persistence
    target: T-017
    type: alternative_to
    rationale: "IFEO Debugger/GlobalFlag persistence hijacks target process launch via registry, operating as an alternative persistence layer to T-017's documented five layers."

  - source: concept-silent-process-exit
    target: concept-ifeo-persistence
    type: chains_to
    rationale: "The material bundles GlobalFlag/Silent Process Exit as 'a nice addition to the traditional IFEO' — Silent Process Exit extends IFEO configuration with exit-triggered execution."

  - source: concept-appinit-dlls
    target: concept-classic-dll-injection
    type: alternative_to
    rationale: "AppInit_DLLs achieves process-wide DLL injection through registry-driven loader hooking rather than the per-target CreateRemoteThread approach of classic DLL injection."
```

### Concept Nodes

```yaml
concepts:
  - id: "concept-appinit-dlls"
    name: "AppInit_DLLs Registry Persistence"
    category: attack-pattern
    description: "When LoadAppInit_DLLs (REG_DWORD) is set to 1 under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows, every newly created user-mode process linked against User32.dll loads the comma-separated DLLs listed in AppInit_DLLs (REG_SZ). Requires administrative privileges. Documented as used by APT39, CherryPicker, and T9000. Operator must avoid infinite loops where the injected DLL spawns a process that re-triggers AppInit loading."
    relevant_to: [T-017]
    tags: [persistence, registry, dll-injection, appinit, user32]

  - id: "concept-ifeo-persistence"
    name: "Image File Execution Options Persistence"
    category: attack-pattern
    description: "IFEO registry keys under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options allow an operator to attach a Debugger value to a target executable, redirecting launch to an attacker binary. The material documents two variants: 'process start' (debugger redirect on launch) and 'silent.exe' variant. Requires administrative privileges."
    relevant_to: [T-017]
    tags: [persistence, registry, ifeo, debugger-hijack]

  - id: "concept-silent-process-exit"
    name: "Silent Process Exit via GlobalFlag"
    category: attack-pattern
    description: "Configured via Gflags.exe (Windows SDK, located at C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64) or directly via the GlobalFlag registry key. The 'Silent Process Exit' feature monitors an exiting process (the 'Image') and invokes a configured 'Monitor' process. Used as a persistence trigger fired on process termination rather than on system boot or process launch. GflagsX by Pavel Yosifovich provides a modern GUI for managing these flags."
    relevant_to: [T-017]
    tags: [persistence, globalflag, gflags, silent-process-exit, process-exit-trigger]

  - id: "concept-service-imagepath-modification"
    name: "Service ImagePath/binPath/FailureCommand Persistence"
    category: attack-pattern
    description: "Existing or newly created Windows services can be modified for persistence by altering ImagePath (registry key holding the absolute path to the service binary), binPath (the command-line passed to the service binary), or FailureCommand (executed when the service fails to start or terminates unexpectedly). Modifications performed via sc.exe or the CreateService API. Service modification produces reboot-survivable execution via SCM."
    relevant_to: [T-017]
    tags: [persistence, services, scm, imagepath, failurecommand]

  - id: "concept-port-monitor-persistence"
    name: "Port Monitor Persistence"
    category: attack-pattern
    description: "Print Spooler port monitors are DLLs loaded into the spoolsv.exe service context. Adding a port monitor via AddMonitor API or registry modification under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors causes the Spooler service to load the attacker DLL on service start. Survives reboots because Spooler auto-starts. Listed in the SEC670 course roadmap as a Lab 4.1-adjacent persistence module."
    relevant_to: [T-017]
    tags: [persistence, port-monitor, print-spooler, dll-load]

  - id: "concept-wmi-event-subscription"
    name: "WMI Event Subscription Persistence"
    category: attack-pattern
    description: "Windows Management Instrumentation event subscriptions (__EventFilter + __EventConsumer bindings) execute attacker-defined actions on system events (process creation, logon, timed triggers). Documented in the SEC670 course roadmap as a persistence module. Executes in the WMI provider host context (WmiPrvSE.exe) and survives reboots without modifying file system or registry keys visible to typical persistence scanners."
    relevant_to: [T-017]
    tags: [persistence, wmi, event-subscription, wmiPrvSE]

  - id: "concept-classic-dll-injection"
    name: "Classic CreateRemoteThread DLL Injection"
    category: attack-pattern
    description: "The legacy four-step DLL injection flow documented in SEC670: (1) obtain a handle to the target process, (2) allocate memory in the target via VirtualAllocEx, (3) write the DLL path string to the allocated region via WriteProcessMemory, (4) spawn a remote thread via CreateRemoteThread with start address pointing to LoadLibraryA/W. Requires the target process to expose LoadLibrary in its export table."
    relevant_to: [T-013]
    tags: [injection, dll-injection, create-remote-thread, virtual-alloc-ex]

  - id: "concept-apc-queue-thread-quantum"
    name: "APC Queue and Thread Quantum Scheduling"
    category: os-internal
    description: "Per the SEC670 review question, the APC queue is the mechanism that allows threads to process routines when entering their quantum. User-mode APCs drain during alertable waits; kernel APCs drain at IRQL drop. Thread quantum entry provides a scheduling window where queued APCs dispatch — the same window Early Cascade (T-012) targets with pre-LdrInitializeThunk APCs."
    relevant_to: [T-012, T-007]
    tags: [apc, thread-scheduling, quantum, windows-internals]

  - id: "concept-win32-find-data"
    name: "WIN32_FIND_DATA Structure"
    category: windows-structure
    description: "User-mode structure that holds the attributes of a file returned by FindFirstFile/FindNextFile. Distinguished from KUSER_SHARED_DATA (shared user/kernel page containing system time and tick count) and FILE_OBJECT (the kernel-mode structure representing an open file instance). The SEC670 review answer identifies WIN32_FIND_DATA as the user-mode file-attribute structure."
    relevant_to: []
    tags: [windows-structure, file-io, orphan, user-mode]

  - id: "concept-ms-dos-pe-header"
    name: "MS-DOS / PE Header Layout"
    category: windows-structure
    description: "PE files begin with an MS-DOS stub. The SEC670 review question asks what byte typically follows the MS-DOS header — establishing that the operator must recognize the MS-DOS header boundary to navigate to the PE header (e_lfanew field at offset 0x3C points to 'PE\\0\\0'). Required knowledge for manual PE parsing in injection and module-stomping techniques."
    relevant_to: [T-007, T-013]
    tags: [pe-format, ms-dos-header, windows-structure, pe-parsing]

  - id: "concept-sddl-security-descriptor"
    name: "SDDL Security Descriptor Definition Language"
    category: os-internal
    description: "Security Descriptor Definition Language is the language used to describe the security of a Windows object descriptor. The SEC670 review question confirms SDDL (not ACL or DACL, which are components within a security descriptor) is the descriptive language. sc.exe is the command-line utility for viewing an object's security descriptor."
    relevant_to: []
    tags: [security-descriptor, sddl, acl, orphan, windows-internals]

  - id: "concept-itask-scheduler-com"
    name: "ITaskScheduler COM Interface"
    category: windows-structure
    description: "COM interface used to create enumeration objects for scheduled tasks. SEC670 review question identifies ITaskScheduler (not IUnknown) as the interface called to create a task enumeration object. Relevant to scheduled-task persistence enumeration and creation via COM rather than the schtasks.exe command-line."
    relevant_to: [T-017]
    tags: [com, scheduled-task, iTaskScheduler, windows-internals]

  - id: "concept-kuser-shared-data"
    name: "KUSER_SHARED_DATA"
    category: windows-structure
    description: "User-readable shared page (fixed virtual address 0x7FFE0000 on x86, 0x7FFE0000 on x64) mapped read-only into every process. Contains system time, tick count, CPU information, and other low-overhead globally-shared values. Distinguished from WIN32_FIND_DATA and FILE_OBJECT in the SEC670 review question. Useful for system-time queries without syscalls."
    relevant_to: []
    tags: [windows-structure, shared-data, orphan, user-mode, kernel-shared]

  - id: "concept-thread-object-residency"
    name: "Thread Object Residency in System Space"
    category: os-internal
    description: "Per the SEC670 review question, when a new thread is created the thread object resides in system (kernel) space, not user space and not the process handle table. Thread objects are kernel structures (ETHREAD/KTHREAD) accessible from user mode only through handles. Establishes why thread manipulation requires object-handle access patterns."
    relevant_to: [T-007, T-012]
    tags: [thread, kernel-object, ethread, windows-internals]
```

### Detection Insights

```yaml
detection:
  - indicator: "LoadAppInit_DLLs set to 1 in HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
    source: windows-security-log
    confidence: high
    relevant_to: [T-017]
    description: "Registry modification of LoadAppInit_DLLs REG_DWORD to 0x1 enables AppInit_DLLs loading. Monitor via Sysmon Event ID 13 (Registry Value Set) targeting the specific value path, or via Windows Security Log 4657 (sensitive registry value modification) when SACL auditing is configured on the key."
    bypassed_by: "not discussed"

  - indicator: "AppInit_DLLs REG_SZ modified to include DLL path list"
    source: sysmon
    confidence: high
    relevant_to: [T-017]
    description: "Sysmon Event ID 13 (Registry Value Set) on HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs captures the comma-separated DLL path list. Alert on any non-empty value, especially paths outside System32 or to non-Microsoft-signed binaries."
    bypassed_by: "not discussed"

  - indicator: "GlobalFlag set with Silent Process Exit flag in HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<target>\\GlobalFlag"
    source: sysmon
    confidence: medium
    relevant_to: [T-017]
    description: "Sysmon Event ID 13 captures GlobalFlag registry value modification under an IFEO subkey. The Silent Process Exit flag (0x2000) combined with ReportingMode and MonitorProcess values under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit indicates exit-triggered persistence."
    bypassed_by: "not discussed"

  - indicator: "Service ImagePath or binPath modified to non-standard path"
    source: windows-security-log
    confidence: high
    relevant_to: [T-017]
    description: "Windows Security Log Event 467 (Service configuration changed) and Sysmon Event ID 13 (registry modifications to HKLM\\SYSTEM\\CurrentControlSet\\Services\\<svc>\\ImagePath) flag service binary path changes. Alert when the new path points outside System32 or to unsigned binaries."
    bypassed_by: "not discussed"

  - indicator: "FailureCommand registry value set on a service"
    source: sysmon
    confidence: medium
    relevant_to: [T-017]
    description: "FailureCommand under a service's registry key executes when the service fails. Sysmon Event ID 13 on HKLM\\SYSTEM\\CurrentControlSet\\Services\\<svc>\\FailureCommand captures the value. Alert on any value set on services that previously had no FailureCommand configured."
    bypassed_by: "not discussed"

  - indicator: "New port monitor registered via AddMonitor or Print\\Monitors registry write"
    source: sysmon
    confidence: high
    relevant_to: [T-017]
    description: "Sysmon Event ID 13 on HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors captures port monitor additions. Alert on monitors pointing to DLLs outside the standard spool\\drivers directory or to non-Microsoft-signed binaries."
    bypassed_by: "not discussed"

  - indicator: "Remote thread creation in notepad.exe with LoadLibrary start address"
    source: behavioral
    confidence: medium
    relevant_to: [T-013]
    description: "The classic DLL injection walk-through targets notepad.exe with CreateRemoteThread on LoadLibraryA. Behavioral detection: CreateRemoteThread on a low-privilege process like notepad is anomalous. Combined with the start address pointing inside LoadLibrary range, indicates DLL injection specifically."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "AppInit_DLLs Enabled"
    logsource: sysmon
    condition_summary: "EventID 13 with TargetObject matching 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\LoadAppInit_DLLs' and Details containing DWORD 0x00000001"

  - title: "AppInit_DLLs Path List Modified"
    logsource: sysmon
    condition_summary: "EventID 13 with TargetObject ending in 'AppInit_DLLs' and Details not containing empty string"

  - title: "Silent Process Exit GlobalFlag Set"
    logsource: sysmon
    condition_summary: "EventID 13 with TargetObject containing 'Image File Execution Options' and 'GlobalFlag' and Details containing '0x00002000' or '+ 0x2000'"

  - title: "Service ImagePath Modified to Non-System Path"
    logsource: sysmon
    condition_summary: "EventID 13 with TargetObject matching 'Services\\\\.*\\\\ImagePath' and Details not containing '\\System32\\' and not containing '\\SysWOW64\\'"

  - title: "FailureCommand Set on Existing Service"
    logsource: sysmon
    condition_summary: "EventID 13 with TargetObject matching 'Services\\\\.*\\\\FailureCommand' and Details not empty"
```

### Operational Chains

```yaml
chains:
  - name: "AppInit_DLLs Persistence Chain"
    description: "Configure registry to inject attacker DLL into every newly launched User32-linked process on the host."
    steps:
      - technique: "registry write to HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
        role: "Set LoadAppInit_DLLs REG_DWORD to 1 to enable the loader hook"
      - technique: "registry write to AppInit_DLLs REG_SZ"
        role: "Set the comma-separated list of attacker DLL paths to be loaded by every User32-linked process"
      - technique: T-017
        role: "Persistence layer active — every new process launch triggers DLL load"
    notes: "Requires administrative privileges. Operator must avoid infinite loops where the injected DLL spawns a process that re-triggers AppInit loading. Process must link against User32.dll to be affected."

  - name: "Silent Process Exit Persistence Chain"
    description: "Configure IFEO GlobalFlag so that an attacker payload fires when a watched process exits."
    steps:
      - technique: "registry write to HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<watched>\\GlobalFlag"
        role: "Set the Silent Process Exit flag (0x2000) on the process to monitor for exit"
      - technique: "registry write to HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\<watched>\\ReportingMode and MonitorProcess"
        role: "Configure the monitor process to invoke when the watched process exits"
      - technique: T-017
        role: "Persistence layer active — process exit triggers attacker payload"
    notes: "Material mentions Gflags.exe (Windows SDK) and the GflagsX GUI tool by Pavel Yosifovich as configuration utilities. GlobalFlag is described as 'a nice addition to the traditional IFEO' — chains onto an IFEO configuration rather than replacing it."

  - name: "Service ImagePath Modification Chain"
    description: "Modify an existing or newly created service's ImagePath to point at attacker binary for SCM-driven execution."
    steps:
      - technique: "sc.exe config or CreateService API call"
        role: "Modify the ImagePath/binPath of an existing service or create a new service pointing at the attacker binary"
      - technique: "optional: set FailureCommand"
        role: "Add failure-triggered execution so the attacker payload also fires if the service is terminated or fails to start"
      - technique: T-017
        role: "Persistence layer active — service start on boot or on failure triggers attacker binary"
    notes: "Material emphasizes existing services can be modified in multiple areas (ImagePath, binPath, FailureCommand). Using existing services reduces operational footprint versus creating new ones."

  - name: "Classic DLL Injection Walk-through"
    description: "Legacy per-target DLL injection via CreateRemoteThread with LoadLibrary start address."
    steps:
      - technique: "OpenProcess on target (e.g., notepad.exe)"
        role: "Obtain handle to target process"
      - technique: "VirtualAllocEx in target"
        role: "Allocate memory for the DLL path string in the target process"
      - technique: "WriteProcessMemory"
        role: "Write the DLL path string to the allocated memory"
      - technique: T-013
        role: "CreateRemoteThread with start address = LoadLibraryA/W and argument = allocated DLL path memory"
    notes: "Documented in SEC670 as a walk-through flow. Requires the target process to expose LoadLibrary in its IAT/export table. Detectable via CreateRemoteThread behavioral telemetry."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "proposed-appinit-dlls-persistence"
    title: "AppInit_DLLs as Standalone Persistence Technique"
    kind: proposed-technique
    description: "SEC670 documents AppInit_DLLs across multiple units (5, 6, 8, 9) as a registry-driven DLL injection persistence mechanism with specific requirements: User32.dll linking of targets, LoadAppInit_DLLs gate, admin privileges, and infinite-loop avoidance. The vault's T-017 persistence suite (COM hijack, NTFS EA, schtask, TLS callback, PhantomPersist) does not include AppInit_DLLs. Given the material's repeated emphasis and the technique's historical use by APT39, CherryPicker, and T9000, this would merit its own T-NNN card or an extension to T-017."
    would_relate_to: [T-017, T-013]
    source_units: ["unit 5", "unit 6", "unit 8", "unit 9"]
    tags: [persistence, appinit-dlls, registry, coverage-gap, proposed]

  - id: "proposed-ifeo-persistence"
    title: "Image File Execution Options Persistence"
    kind: proposed-technique
    description: "SEC670 dedicates Lab 4.2 (Sauron IFEO) and Lab 4.3 (IFEOPersisto) to IFEO persistence with two variants documented: 'process start' (debugger redirect on launch) and 'silent.exe'. The vault's T-017 does not document IFEO. IFEO persistence is distinct enough — uses Debugger/GlobalFlag registry values rather than COM hijack or schtask — to merit its own T-NNN card."
    would_relate_to: [T-017]
    source_units: ["unit 2", "unit 28"]
    tags: [persistence, ifeo, registry, debugger-hijack, proposed]

  - id: "proposed-silent-process-exit-persistence"
    title: "Silent Process Exit via GlobalFlag Persistence"
    kind: proposed-technique
    description: "SEC670 covers Silent Process Exit configured via Gflags.exe / GlobalFlag registry key as a process-exit-triggered persistence mechanism distinct from boot-time or launch-time persistence. Units 11, 12, 22, 23, 27 document the configuration via GflagsX GUI tool. The vault has no card for exit-triggered persistence primitives. Would relate to T-017 as an additional persistence layer with a different trigger condition."
    would_relate_to: [T-017]
    source_units: ["unit 11", "unit 12", "unit 22", "unit 23", "unit 27"]
    tags: [persistence, silent-process-exit, globalflag, gflags, exit-trigger, proposed]

  - id: "proposed-service-modification-persistence"
    title: "Service ImagePath/binPath/FailureCommand Persistence"
    kind: proposed-technique
    description: "SEC670 Book 4 documents modifying existing services via ImagePath, binPath, and FailureCommand registry keys as a persistence mechanism. The vault's T-017 persistence suite does not include service-based persistence. Service persistence has unique operational properties (SCM-driven, auto-start, FailureCommand provides redundancy on service failure) that distinguish it from the documented five layers."
    would_relate_to: [T-017]
    source_units: ["unit 1", "unit 10"]
    tags: [persistence, services, scm, imagepath, failurecommand, proposed]

  - id: "proposed-port-monitor-persistence"
    title: "Port Monitor Persistence"
    kind: proposed-technique
    description: "SEC670 Book 4 roadmap includes a port monitors module for persistence. Port monitor persistence loads an attacker DLL into the Print Spooler service context via the AddMonitor API or Print\\Monitors registry modification. The vault has no coverage of this persistence surface. Would relate to T-017 as an additional persistence layer with Spooler-context execution."
    would_relate_to: [T-017]
    source_units: ["unit 1", "unit 2", "unit 7", "unit 26"]
    tags: [persistence, port-monitor, print-spooler, proposed]

  - id: "proposed-wmi-event-subscription-persistence"
    title: "WMI Event Subscription Persistence"
    kind: proposed-technique
    description: "SEC670 Book 4 roadmap lists WMI Event Subscriptions as a persistence module. WMI event subscriptions execute attacker actions on system events (process creation, logon, timed) within WmiPrvSE.exe context, surviving reboots without typical filesystem or registry persistence-scan coverage. The vault's T-017 does not document WMI persistence. Would extend T-017's persistence surface."
    would_relate_to: [T-017]
    source_units: ["unit 1", "unit 2", "unit 7", "unit 26"]
    tags: [persistence, wmi, event-subscription, proposed]

  - id: "gap-persistence-surface-coverage"
    title: "T-017 Persistence Surface Under-Covered vs SEC670"
    kind: coverage-gap
    description: "SEC670's 'Persistence: Die Another Day' module covers services, registry keys, AppInit_DLLs, IFEO, GlobalFlag/Silent Process Exit, port monitors, and WMI event subscriptions. The vault's T-017 documents only COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist — five layers that do not overlap with most of the SEC670 surface. Cross-cutting metadata on T-017 indicating which persistence surfaces the vault covers vs. which it omits would aid operator navigation."
    would_relate_to: [T-017]
    source_units: ["unit 1", "unit 2", "unit 7", "unit 10", "unit 11", "unit 26"]
    tags: [persistence, coverage-gap, t-017]

  - id: "cross-source-convergence-classic-dll-injection"
    title: "Classic CreateRemoteThread DLL Injection as Pedagogical Baseline"
    kind: cross-source-convergence
    description: "The classic four-step CreateRemoteThread DLL injection flow (obtain handle → allocate → write → remote thread) appears as the introductory walk-through across multiple SEC670 units and is the foundational pattern that MalDev Academy and CRTO also establish before introducing modern variants. The vault's T-013 documents the modern injection methods but does not surface this baseline flow explicitly. Documenting it as the historical reference pattern for the T-013 method set would orient readers transitioning from training material to the vault."
    would_relate_to: [T-013]
    source_units: ["unit 3"]
    tags: [injection, dll-injection, create-remote-thread, pedagogical-baseline, convergence]

  - id: "emerging-windows-internals-vocabulary"
    title: "Windows Internals Vocabulary Cards for Review-Question Material"
    kind: coverage-gap
    description: "SEC670 units 13–21 and 24–25 are review-question material that surfaces foundational Windows internals vocabulary: WIN32_FIND_DATA, KUSER_SHARED_DATA, FILE_OBJECT, MS-DOS header byte layout, thread-as-schedulable-entity, thread object kernel-space residency, SDDL, sc.exe security descriptor viewing, ITaskScheduler COM interface. The vault's technique cards assume this vocabulary without defining it. A glossary-level concept-node set (produced in this batch) captures the OS-internals backdrop the vault's tradecraft depends on."
    would_relate_to: []
    source_units: ["unit 13", "unit 14", "unit 15", "unit 16", "unit 17", "unit 18", "unit 19", "unit 20", "unit 21", "unit 24", "unit 25"]
    tags: [windows-internals, vocabulary, review-material, orphan]
```