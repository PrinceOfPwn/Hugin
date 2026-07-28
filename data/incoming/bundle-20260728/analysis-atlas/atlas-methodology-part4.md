## Synthesis Summary

This batch maps to T-004 (PEB Walker), T-014 (NtCreateUserProcess), T-015 (PPID Spoofing), T-016 (EDR Evasion Suite), T-017 (Five-Layer Persistence), and T-023 (Client Capabilities). The SANS SEC670 Section 4-6 material covers Windows security descriptors and SDDL string format, port monitor architecture bridging user-mode spoolsv.exe to kernel drivers via AddPrinter, CIM/WMI schema structure (CIM_ vs Win32_ prefixes, Core/Common/Extended class levels), the NTDLL (native) vs WIN32K.SYS (GUI) syscall division, Heaven's Gate 32-to-64-bit Wow64 transition, and DLL loading API parallels (LoadLibrary/GetProcAddress vs dlopen/dlsym). The batch also lists in course roadmaps — but does not substantively detail — persistence mechanisms the vault's T-017 card does not currently cover: services, port monitors, IFEO, WMI event subscriptions, binary patching, and registry key persistence. Approximately 25 of the 40 units are duplicate or near-duplicate Section 4/5/6 course roadmap slides. The material fills the OS-internals gap that reading Rust source code alone does not provide: it explains the security descriptor data structures, CIM object model, and port monitor bridging architecture that the vault's persistence and syscall techniques operate on.

## Knowledge Graph Contributions

### Discovered Relationships

```yaml
edges:
  - source: "securable-objects-security-attributes"
    target: T-014
    type: enables
    rationale: "SEC670 unit 1 establishes that the Create* API family accepts SECURITY_ATTRIBUTES to attach a security descriptor to newly created securable objects including processes; NtCreateUserProcess direct process creation relies on this same descriptor attachment mechanism."

  - source: "securable-objects-security-attributes"
    target: T-015
    type: enables
    rationale: "SEC670 unit 1 documents that processes and threads are securable objects with security descriptors enforced during OpenProcess-style handle acquisition; PPID spoofing techniques that open parent process handles must satisfy these descriptor checks."

  - source: "sddl-security-descriptor-string-format"
    target: T-017
    type: enhances
    rationale: "SEC670 units 17-19 describe SDDL as the string format used by ConvertStringSecurityDescriptorToSecurityDescriptor for setting DACL/SACL/Owner/Group on securable objects; persistence techniques that install services, scheduled tasks, or COM objects with custom ACLs use SDDL to express the access control configuration."

  - source: "port-monitors-print-spooler-bridge"
    target: T-017
    type: alternative_to
    rationale: "SEC670 unit 23 describes port monitors as a user-mode (spoolsv.exe) to kernel-mode bridge loaded as DLLs via AddPrinter; this constitutes a persistence vector alternative to the five layers the vault's T-017 card documents."

  - source: "cim-wmi-schema-model"
    target: T-023
    type: concept_link
    rationale: "SEC670 units 27-30 describe the CIM schema hierarchy (Core/Common/Extended, CIM_ and Win32_ prefixes) that the WMI execution capability in T-023 (experimental/harvest/wmi_exec.rs) queries against; understanding the schema structure is prerequisite to crafting WMI queries."

  - source: "heavens-gate-wow64-transition"
    target: T-002
    type: alternative_to
    rationale: "SEC670 unit 34 describes Heaven's Gate as the 32-bit process to 64-bit syscall transition via Wow64; while T-002's Hell's/Halo's/Tartarus Gate resolves SSNs from a 64-bit ntdll, Heaven's Gate is an alternative dispatch path for 32-bit payloads needing to reach the 64-bit syscall layer."

  - source: "ntdll-vs-win32k-syscall-division"
    target: T-001
    type: requires
    rationale: "SEC670 unit 33 distinguishes NTDLL.DLL native syscalls (NtOpenProcess, NtCreateProcess) from WIN32.DLL/WIN32K.SYS GUI syscalls (NtUserOpenClipboard); RecycledGate indirect syscall dispatch via ntdll gadgets operates only on the native NTDLL syscall surface, not the Win32k GUI surface."

  - source: "dll-loadlibrary-getprocaddress-resolution"
    target: T-004
    type: concept_link
    rationale: "SEC670 unit 38 documents LoadLibrary/GetProcAddress as the Win32 parallel to dlopen/dlsym; the PEB walker technique in T-004 reimplements this resolution manually by walking the PEB loader table to avoid calling these functions directly."
```

### Concept Nodes

```yaml
concepts:
  - id: "securable-objects-security-attributes"
    name: "Securable Objects and SECURITY_ATTRIBUTES"
    category: "os-internal"
    description: "Windows securable objects — files, processes, threads, registry keys — carry a security descriptor that the SRM checks on every access request. The Create* Win32 API family (CreateProcess, CreateThread, CreateFile) accepts a SECURITY_ATTRIBUTES structure pointer to attach a descriptor at object creation. OpenProcess and similar handle-acquisition APIs trigger an access check against this descriptor, returning ERROR_ACCESS_DENIED when the caller lacks the requested access rights in the DACL."
    relevant_to: [T-014, T-015, T-017]
    tags: [security-descriptor, dacl, sacl, security-attributes, access-check, windows-internals]

  - id: "sddl-security-descriptor-string-format"
    name: "Security Descriptor Definition Language (SDDL)"
    category: "windows-structure"
    description: "SDDL is a string format consumed by ConvertSecurityDescriptorToStringSecurityDescriptor and ConvertStringSecurityDescriptorToSecurityDescriptor. The string encodes Owner (O:), Primary Group (G:), DACL (D:), and SACL (S:) sections, each with control flags. ACE strings follow the form (AceType;;AccessMask;;;Sid) — e.g. (A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-0-0) is an ACCESS_ALLOWED_ACE_TYPE granting READ_CONTROL|WRITE_DAC|WRITE_OWNER|GENERIC_ALL to the NULL SID."
    relevant_to: [T-017]
    tags: [sddl, security-descriptor, dacl, sacl, ace, access-mask, windows-internals]

  - id: "port-monitors-print-spooler-bridge"
    name: "Windows Port Monitors (spoolsv.exe to Kernel Bridge)"
    category: "os-internal"
    description: "Windows print monitors come in two types: language monitors and port monitors. A port monitor bridges user-mode spoolsv.exe (the Windows Print Spooler service) to a kernel-mode port driver. Port monitors are implemented as DLLs loaded by spoolsv.exe and registered through the Win32 AddPrinter API. Because spoolsv.exe loads these DLLs at service start, registering a malicious port monitor DLL achieves persistence with SYSTEM-equivalent privileges in the spooler process."
    relevant_to: [T-017]
    tags: [persistence, port-monitor, spoolsv, print-spooler, addprinter, dll-loading]

  - id: "cim-wmi-schema-model"
    name: "Common Information Model (CIM) and WMI Schemas"
    category: "windows-structure"
    description: "CIM is an industry-standard object-oriented model WMI uses to represent systems, processes, devices, and applications. CIM defines three class levels: Core (general managed objects), Common (system, application, network extensions), and Extended (technology-specific). Classes are grouped into schemas: the CIM Schema contains classes prefixed CIM_ (Core and Common definitions), and the Win32 Schema contains classes prefixed Win32_ (Extended CIM specific to the Win32 environment). Developers can author custom classes in either schema."
    relevant_to: [T-023]
    tags: [cim, wmi, schema, win32-classes, object-model, windows-internals]

  - id: "ntdll-vs-win32k-syscall-division"
    name: "NTDLL Native vs WIN32K.SYS GUI Syscall Split"
    category: "os-internal"
    description: "Windows exposes two syscall surfaces. NTDLL.DLL provides native syscalls (NtOpenProcess, NtCreateProcess) that enter the kernel and executive directly. WIN32.DLL (user32/gdi32) provides GUI syscalls (NtUserOpenClipboard, NtUserCloseClipboard) that route into WIN32K.SYS, a separate kernel-mode subsystem. A console/native thread makes only NTDLL syscalls; a GUI thread additionally issues WIN32K syscalls. Syscall dispatch techniques operating on ntdll gadgets do not cover the WIN32K syscall surface."
    relevant_to: [T-001, T-002, T-004]
    tags: [ntdll, win32k, syscalls, native, gui, windows-internals]

  - id: "heavens-gate-wow64-transition"
    name: "Heaven's Gate (Wow64 32-to-64-bit Syscall Transition)"
    category: "attack-pattern"
    description: "On 64-bit Windows, 32-bit processes run under Wow64 (Windows-on-Windows-64). Wow64 presents a transition layer — historically the 0x33 segment selector in the 32-bit TEB — that lets 32-bit code issue 64-bit syscalls directly. By far-jumping through this gate, a 32-bit payload can bypass 32-bit ntdll hooks and dispatch native syscalls on the 64-bit syscall surface. The technique is distinct from SSN-resolution gates (Hell's/Halo's/Tartarus) which operate within a single bitness."
    relevant_to: [T-002]
    tags: [heavens-gate, wow64, 32-bit, 64-bit, syscall, transition, attack-pattern]

  - id: "dll-loadlibrary-getprocaddress-resolution"
    name: "Win32 DLL Loading APIs (LoadLibrary / GetProcAddress)"
    category: "os-internal"
    description: "Windows provides LoadLibrary/FreeLibrary for explicit DLL load and unload, and GetProcAddress for symbol address resolution. These are the Win32 parallels to Linux dlopen/dlclose/dlsym. Both PE (Windows) and ELF (Linux) export symbols that the loader resolves at runtime. Manual resolution techniques (PEB walking, export table parsing) reimplement GetProcAddress behavior without invoking the API directly, avoiding IAT-based detection of which functions a module imports."
    relevant_to: [T-004]
    tags: [loadlibrary, getprocaddress, dlopen, dlsym, dll, symbol-resolution, windows-internals]
```

### Detection Insights

```yaml
detection:
  - indicator: "New port monitor DLL registered via AddMonitor / AddPrinter"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-017]
    description: "SEC670 unit 23 documents that port monitors are loaded by spoolsv.exe and registered via the Win32 AddPrinter API family. A new port monitor registration appears in the Windows Security log under Print Service event sources and as a spoolsv.exe child DLL load. The monitor DLL path typically resolves to %SystemRoot%\\System32\\spool\\prtprocs\\x64 or a spool\\drivers directory. Anomalous paths or unsigned DLLs in these locations flag malicious monitor registration."
    bypassed_by: "not discussed"

  - indicator: "spoolsv.exe loads unsigned or non-Microsoft DLL"
    source: sysmon
    confidence: high
    relevant_to: [T-017]
    description: "Once a port monitor is registered, spoolsv.exe loads the monitor DLL at service start. Sysmon Event ID 7 (Image Load) captures the load with the Image field set to spoolsv.exe and the ImageLoaded field pointing to the monitor DLL path. Microsoft-signed spooler DLLs are baseline; a non-Microsoft or unsigned DLL loaded by spoolsv.exe is a high-confidence persistence indicator."
    bypassed_by: "not discussed"

  - indicator: "WMI permanent event subscription created (__EventFilter / __EventConsumer / __FilterToConsumerBinding)"
    source: sysmon
    confidence: high
    relevant_to: [T-017, T-023]
    description: "SEC670 Section 4 lists WMI Event Subscriptions as a persistence mechanism. Sysmon Event ID 19 (WmiFilterEvent), 20 (WmiConsumerEvent), and 21 (WmiFilterConsumerBinding) fire when an attacker registers a permanent event subscription. The filter, consumer (typically ActiveScriptEventConsumer or CommandLineEventConsumer), and binding together constitute the persistence triad. The CommandLineTempPath or ScriptText fields in the consumer event contain the payload."
    bypassed_by: "not discussed"

  - indicator: "IFEO Debugger registry value created under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
    source: windows-security-log
    confidence: medium
    relevant_to: [T-017]
    description: "SEC670 Section 4 lists IFEO (Image File Execution Options) as a persistence mechanism. An IFEO Debugger value under a target executable's IFEO key redirects execution of that target to a specified binary on launch. Registry operation logging (Sysmon Event ID 12-13, or Windows Security event 4657 on audited keys) captures the Debugger value creation. Common abused IFEO targets include sethc.exe, utilman.exe, and other accessibility binaries."
    bypassed_by: "not discussed"

  - indicator: "New service binary path with non-standard location or SYSTEM privileges"
    source: sysmon
    confidence: high
    relevant_to: [T-017]
    description: "SEC670 Section 4 lists Services Revisited as a persistence mechanism. Sysmon Event ID 1 captures process creation of a service binary; Windows Security Event ID 4697 (Service Installed) logs the service name, binary path, and account. Service binaries located in user-writable paths (e.g. C:\\Users\\Public), with SYSTEM service type, or lacking a valid digital signature are high-confidence indicators."
    bypassed_by: "not discussed"

sigma_ideas:
  - title: "Suspicious Port Monitor DLL Registration"
    logsource: windows-security
    condition_summary: "Print Service or Service Control Manager events indicating AddMonitor or AddPrinter registered a port monitor DLL whose path is outside %SystemRoot%\\System32\\spool or whose DLL is not Microsoft-signed"

  - title: "spoolsv.exe Loads Non-Microsoft DLL"
    logsource: sysmon
    condition_summary: "Sysmon Event ID 7 where Image = spoolsv.exe and ImageLoaded is not signed by Microsoft or path is outside standard spool directories"

  - title: "WMI Permanent Event Subscription Triad"
    logsource: sysmon
    condition_summary: "Sysmon Event IDs 19, 20, 21 firing in sequence within a short window, indicating __EventFilter, __EventConsumer, and __FilterToConsumerBinding were registered together"

  - title: "IFEO Debugger Value Creation"
    logsource: sysmon
    condition_summary: "Sysmon Event ID 12-13 registry event for TargetObject containing 'Image File Execution Options' and a Debugger value being set"
```

### Operational Chains

```yaml
chains:
  - name: "Port Monitor Persistence Installation"
    description: "Register a malicious port monitor DLL to be loaded by spoolsv.exe on Print Spooler service start"
    steps:
      - technique: "credential access or SYSTEM acquisition"
        role: "Obtain sufficient privileges to install a print monitor (typically local SYSTEM or administrator)"
      - technique: T-017
        role: "Persist the monitor DLL to disk in a spool-recognized path"
      - technique: "AddPrinter / AddMonitor Win32 API invocation"
        role: "Register the DLL as a port monitor so spoolsv.exe loads it on next service start"
      - technique: "spoolsv.exe restart trigger"
        role: "Restart or wait for the Print Spooler service to load the monitor DLL"
    notes: "SEC670 unit 23 documents port monitors as a user-mode to kernel-mode bridge loaded by spoolsv.exe; the material does not detail the specific privilege level required or the exact registry key layout for monitor registration."

  - name: "WMI Event Subscription Persistence"
    description: "Register a permanent WMI event subscription that triggers payload execution on system events"
    steps:
      - technique: "WMI namespace access (root\\subscription)"
        role: "Acquire write access to the root\\subscription WMI namespace"
      - technique: "__EventFilter instance creation"
        role: "Define the trigger event (e.g. startup, logon, timer)"
      - technique: "__EventConsumer instance creation"
        role: "Define the action — typically ActiveScriptEventConsumer (VBScript/JScript) or CommandLineEventConsumer"
      - technique: "__FilterToConsumerBinding instance creation"
        role: "Bind the filter to the consumer to activate the subscription"
    notes: "SEC670 Section 4 roadmap lists WMI Event Subscriptions as a persistence topic; the material in this batch does not provide the implementation details, only the curriculum placement. CIM schema background in units 27-30 supports understanding the WMI object model."

  - name: "IFEO Debugger Persistence"
    description: "Set an IFEO Debugger value on a target executable to redirect its launch to an attacker binary"
    steps:
      - technique: "HKLM registry write access"
        role: "Obtain privileges to write under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
      - technique: "IFEO key creation for target executable"
        role: "Create a subkey named after the target binary (e.g. sethc.exe)"
      - technique: "Debugger value set to attacker binary path"
        role: "Set the Debugger string value to the full path of the payload binary"
      - technique: "target executable launch trigger"
        role: "Wait for a user or process to launch the target executable, which now runs the attacker binary instead"
    notes: "SEC670 Section 4 roadmap lists IFEO as a persistence topic (Labs 4.2 Sauron, 4.3 IFEOPersisto); the material in this batch does not provide implementation details beyond the curriculum placement."
```

### LGTM Notes

```yaml
lgtm_notes:
  - id: "ifeo-debugger-persistence"
    title: "Image File Execution Options (IFEO) Debugger Persistence"
    kind: "proposed-technique"
    description: "SEC670 Section 4 dedicates two labs (4.2 Sauron, 4.3 IFEOPersisto) to IFEO-based persistence. The vault's T-017 Five-Layer Persistence card documents COM hijack, NTFS EA, schtask, TLS callback, and PhantomPersist but does not include IFEO. IFEO is a distinct persistence vector operating through the HKLM Image File Execution Options registry key, redirecting target executable launch to an attacker-specified Debugger binary. The mechanism is reusable across accessibility binary hijacks (sethc, utilman), security tool redirects, and arbitrary target hijack."
    would_relate_to: [T-017]
    source_units: ["unit 9", "unit 13", "unit 14", "unit 15", "unit 16"]
    tags: [persistence, ifeo, registry, debugger, accessibility-binary, coverage-gap]

  - id: "port-monitor-persistence"
    title: "Print Spooler Port Monitor Persistence"
    kind: "proposed-technique"
    description: "SEC670 unit 23 substantively documents port monitors as a spoolsv.exe-loaded DLL bridge from user mode to kernel mode, registered via the Win32 AddPrinter API family. The vault's T-017 card does not cover this vector. Port monitor persistence executes in the SYSTEM-privileged spoolsv.exe process and survives reboots, making it a high-value persistence primitive distinct from the five layers currently documented. It would merit its own T-NNN card given the distinct installation mechanism and detection surface."
    would_relate_to: [T-017]
    source_units: ["unit 20", "unit 21", "unit 23"]
    tags: [persistence, port-monitor, spoolsv, print-spooler, addprinter, coverage-gap]

  - id: "wmi-event-subscription-persistence"
    title: "WMI Permanent Event Subscription Persistence"
    kind: "proposed-technique"
    description: "SEC670 Section 4 lists WMI Event Subscriptions as a distinct persistence mechanism, and units 27-30 provide the CIM/WMI schema background (Core/Common/Extended classes, CIM_ and Win32_ prefixes) that the technique operates on. The vault's T-017 card does not document WMI permanent subscriptions (the __EventFilter / __EventConsumer / __FilterToConsumerBinding triad). T-023 includes WMI execution as a client capability, but not the permanent subscription persistence layer. This deserves a separate persistence T-NNN given the distinct object model, installation path, and Sysmon 19/20/21 detection surface."
    would_relate_to: [T-017, T-023]
    source_units: ["unit 27", "unit 28", "unit 29", "unit 30", "unit 31"]
    tags: [persistence, wmi, cim, event-subscription, sysmon-19-20-21, coverage-gap]

  - id: "services-and-binary-patching-persistence-gap"
    title: "Service and Binary Patching Persistence Coverage Gap"
    kind: "coverage-gap"
    description: "SEC670 Section 4 lists Services Revisited and Binary Patching as persistence mechanisms, both absent from the vault's T-017 Five-Layer Persistence card. Service persistence (registering a malicious service binary or hijacking an existing service path) is one of the most common persistence vectors in incident response data. Binary patching persistence modifies an existing on-disk binary to incorporate attacker code. The vault's persistence coverage is currently oriented toward fileless or filesystem-adjacent techniques (COM hijack, NTFS EA, schtask, TLS callback) and would benefit from explicit service and binary-patch technique documentation."
    would_relate_to: [T-017]
    source_units: ["unit 9", "unit 10", "unit 11", "unit 13", "unit 15", "unit 24", "unit 26"]
    tags: [persistence, services, binary-patching, coverage-gap]

  - id: "heavens-gate-wow64-syscall-transition"
    title: "Heaven's Gate (Wow64 32-to-64-bit Syscall Transition)"
    kind: "emerging-tradecraft"
    description: "SEC670 unit 34 documents Heaven's Gate as the Wow64-mediated transition from 32-bit code to 64-bit syscall dispatch via the 0x33 segment selector in the 32-bit TEB. The vault's T-002 (Hell's/Halo's/Tartarus Gate) addresses SSN resolution within a single bitness but does not document cross-bitness syscall dispatch. Heaven's Gate remains relevant for 32-bit payloads operating on 64-bit systems where 32-bit ntdll hooks must be bypassed by jumping to the 64-bit syscall surface. The vault should track this as a distinct dispatch mode alongside RecycledGate, VEH Gate, and Direct."
    would_relate_to: [T-001, T-002]
    source_units: ["unit 34"]
    tags: [heavens-gate, wow64, 32-bit, 64-bit, syscall, cross-bitness, emerging-tradecraft]
```
